package flow

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"bytes"
	"strconv"
	"strings"
	"github.com/lib/pq"
	"github.com/wspr-ncsu/visiblev8/post-processor/core"
)

type Script struct {
	APIs []string
	info *core.ScriptInfo
}

func NewScript(info *core.ScriptInfo) *Script {
	return &Script{
		APIs: make([]string, 0),
		info: info,
	}
}

type flowAggregator struct {
	scriptList map[int]*Script
	lastAction string
}

func NewAggregator() (core.Aggregator, error) {
	return &flowAggregator{
		scriptList: make(map[int]*Script),
	}, nil
}

func (agg *flowAggregator) IngestRecord(ctx *core.ExecutionContext, lineNumber int, op byte, fields []string) error {
	if (ctx.Script != nil) && !ctx.Script.VisibleV8 && (ctx.Origin.Origin != "") {
		offset, err := strconv.Atoi(fields[0])
		if err != nil {
			return fmt.Errorf("%d: invalid script offset '%s'", lineNumber, fields[0])
		}
		var receiver, member string
		switch op {
		case 'g', 's':
			receiver, _ = core.StripCurlies(fields[1])
			member, _ = core.StripQuotes(fields[2])
		case 'n':
			receiver, _ = core.StripCurlies(fields[1])
			receiver = strings.TrimPrefix(receiver, "%")
		case 'c':
			receiver, _ = core.StripCurlies(fields[2])
			member, _ = core.StripQuotes(fields[1])
			member = strings.TrimPrefix(member, "%")
		default:
			return fmt.Errorf("%d: invalid mode '%c'; fields: %v", lineNumber, op, fields)
		}

		if core.FilterName(member) {
			// We have some names (V8 special cases, numeric indices) that are never useful
			return nil
		}

		if strings.Contains(receiver, ",") {
			receiver = strings.Split(receiver, ",")[1]
		}

		var fullName string
		if member != "" {
			fullName = fmt.Sprintf("%s.%s", receiver, member)
		} else {
			fullName = receiver
		}

		script, ok := agg.scriptList[ctx.Script.ID]
		if !ok {
			script = NewScript(ctx.Script)
			agg.scriptList[ctx.Script.ID] = script
		}

		currentAction := fmt.Sprint(offset) + string(',') + fullName

		if agg.lastAction == currentAction && op == 'c' {
			return nil
		}

		script.APIs = append(script.APIs, currentAction)
	}

	return nil
}

var scriptFlowFields = [...]string{
	"isolate",
	"visiblev8",
	"code",
	"sha256",
	"url",
	"evaled_by",
	"apis",
	"first_origin",
	"submission_id",
}

func (agg *flowAggregator) DumpToPostgresql(ctx *core.AggregationContext, sqlDb *sql.DB) error {
	txn, err := sqlDb.Begin()
	if err != nil {
		log.Printf("Error beginning transaction: %v", err)
		return err
	}

	log.Printf("scriptFlow: %d scripts analysed", len(agg.scriptList))

	var queryBuilder strings.Builder
	var params []interface{}

	// Build bulk INSERT query
	queryBuilder.WriteString("INSERT INTO script_flow (")
	queryBuilder.WriteString(strings.Join(scriptFlowFields[:], ", "))
	queryBuilder.WriteString(") VALUES ")

	rowCount := 0
	for _, script := range agg.scriptList {
		if rowCount > 0 {
			queryBuilder.WriteString(", ")
		}
		placeholders := make([]string, len(scriptFlowFields))
		for i := 0; i < len(scriptFlowFields); i++ {
			placeholders[i] = "$" + strconv.Itoa(len(params)+i+1)
		}
		queryBuilder.WriteString("(")
		queryBuilder.WriteString(strings.Join(placeholders, ", "))
		queryBuilder.WriteString(")")
		// Prepare values for this script.
		evaledById := -1
		if script.info.EvaledBy != nil {
			evaledById = script.info.EvaledBy.ID
		}
		params = append(params,
			script.info.Isolate.ID,         // isolate
			script.info.VisibleV8,          // visiblev8
			script.info.Code,               // code
			script.info.CodeHash.SHA2[:],    // sha256
			script.info.URL,                // url
			evaledById,                     // evaled_by
			pq.Array(script.APIs),          // apis
			script.info.FirstOrigin.Origin, // first_origin
			ctx.SubmissionID.String(),      // submission_id
		)
		rowCount++
	}

	if rowCount == 0 {
		log.Printf("No scripts to insert.")
		if err := txn.Commit(); err != nil {
			log.Printf("Error committing empty transaction: %v", err)
			return err
		}
		return nil
	}

	// Use RETURNING to capture the inserted IDs.
	queryBuilder.WriteString(" RETURNING id")
	query := queryBuilder.String()
	log.Printf("Bulk insert query: %s", query)

	rows, err := txn.Query(query, params...)
	if err != nil {
		log.Printf("Error executing bulk insert: %v", err)
		txn.Rollback()
		return err
	}

	var scriptIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			log.Printf("Error scanning returned id: %v", err)
			txn.Rollback()
			return err
		}
		scriptIDs = append(scriptIDs, id)
	}
	rows.Close()

	if err := txn.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		return err
	}

	log.Printf("Inserted %d rows. Retrieved IDs: %v", rowCount, scriptIDs)

	// Now send the collected IDs to the next system.
	status, errDetail, err := sendScriptIDs(scriptIDs)
	if err != nil {
		log.Printf("Error sending script IDs: status=%d, detail=%s", status, errDetail)
		// Update the inserted rows with the error details.
		txn, err := sqlDb.Begin()
		if err != nil {
			log.Printf("Error beginning update transaction: %v", err)
			return err
		}
		// Update rows with the error details.
		_, err = txn.Exec("UPDATE script_flow SET api_status = $1, api_error = $2 WHERE id = ANY($3)",
			status, errDetail, pq.Array(scriptIDs))
		if err != nil {
			log.Printf("Error updating rows with error details: %v", err)
			txn.Rollback()
			return err
		}
		if err := txn.Commit(); err != nil {
			log.Printf("Error committing update transaction: %v", err)
			return err
		}
		return err // or return nil if you want to proceed despite the error
	} else {
		// On success, update the inserted rows to indicate success.
		txn, err := sqlDb.Begin()
		if err != nil {
			log.Printf("Error beginning success update transaction: %v", err)
			return err
		}
		_, err = txn.Exec("UPDATE script_flow SET api_status = $1 WHERE id = ANY($2)",
			status, pq.Array(scriptIDs))
		if err != nil {
			log.Printf("Error updating rows with success status: %v", err)
			txn.Rollback()
			return err
		}
		if err := txn.Commit(); err != nil {
			log.Printf("Error committing success update transaction: %v", err)
			return err
		}
		log.Printf("Script IDs sent successfully with status %d", status)
	}

	return nil
}



// sendScriptIDs sends the script IDs to the next system.
// It returns three values:
// - status code (e.g. 200, 404, etc.),
// - a detailed error string (if any),
// - and an error value.
func sendScriptIDs(ids []int) (int, string, error) {
    payload, err := json.Marshal(ids)
    if err != nil {
        detail := fmt.Sprintf("error marshalling JSON: %v", err)
        return 0, detail, err
    }
    log.Printf("Sending payload: %s", payload)

    url := "http://172.17.0.1:8100/analyze"
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
    if err != nil {
        detail := fmt.Sprintf("error creating POST request: %v", err)
        return 0, detail, err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        detail := fmt.Sprintf("error executing POST request: %v", err)
        return 0, detail, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        detail := fmt.Sprintf("POST request to %s returned status: %s, body: %s", url, resp.Status, body)
        return resp.StatusCode, detail, fmt.Errorf("POST request returned status: %s", resp.Status)
    }

    log.Printf("POST request to %s returned status: %s", url, resp.Status)
    return resp.StatusCode, "", nil
}



func (agg *flowAggregator) DumpToStream(ctx *core.AggregationContext, stream io.Writer) error {
	jstream := json.NewEncoder(stream)

	for _, script := range agg.scriptList {
		evaledBy := script.info.EvaledBy
		evaledById := -1
		if evaledBy != nil {
			evaledById = evaledBy.ID
		}

		jstream.Encode(core.JSONArray{"script_flow", core.JSONObject{
			"ID":          script.info.ID,
			"Isolate":     script.info.Isolate.ID,
			"IsVisibleV8": script.info.VisibleV8,
			"Code":        script.info.Code,
			"URL":         script.info.URL,
			"IsEvaledBy":  evaledById,
			"FirstOrigin": script.info.FirstOrigin,
			"APIs":        script.APIs,
		}})
	}

	return nil
}
