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

    // Build a bulk INSERT statement with placeholders.
    var queryBuilder strings.Builder
    var params []interface{}

    // Write the beginning of the query.
    queryBuilder.WriteString("INSERT INTO script_flow (")
    // Convert the array to a slice so strings.Join works.
    queryBuilder.WriteString(strings.Join(scriptFlowFields[:], ", "))
    queryBuilder.WriteString(") VALUES ")

    rowCount := 0
    // For each script, add a row to the VALUES clause.
    for _, script := range agg.scriptList {
        if rowCount > 0 {
            queryBuilder.WriteString(", ")
        }
        // For each row, add a group of placeholders.
        placeholders := make([]string, len(scriptFlowFields))
        for i := 0; i < len(scriptFlowFields); i++ {
            placeholders[i] = "$" + strconv.Itoa(len(params)+i+1)
        }
        queryBuilder.WriteString("(")
        queryBuilder.WriteString(strings.Join(placeholders, ", "))
        queryBuilder.WriteString(")")

        // Prepare the values for this script.
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

    // If there are no rows to insert, just commit and return.
    if rowCount == 0 {
        log.Printf("No scripts to insert.")
        if err := txn.Commit(); err != nil {
            log.Printf("Error committing empty transaction: %v", err)
            return err
        }
        return nil
    }

    // Add the RETURNING clause to fetch auto-generated IDs.
    queryBuilder.WriteString(" RETURNING id")
    query := queryBuilder.String()
    log.Printf("Bulk insert query: %s", query)

    // Execute the query.
    rows, err := txn.Query(query, params...)
    if err != nil {
        log.Printf("Error executing bulk insert: %v", err)
        txn.Rollback()
        return err
    }

    // Collect the returned IDs.
    var scriptIDs []int
    for rows.Next() {
        var id int
        if err := rows.Scan(&id); err != nil {
            log.Printf("Error scanning returning id: %v", err)
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

    // Now that the transaction is committed, send the collected IDs to the next system.
    if len(scriptIDs) > 0 {
        if err := sendScriptIDs(scriptIDs); err != nil {
            log.Printf("Error sending script IDs: %v", err)
            return err
        }
    } else {
        log.Printf("No script IDs to send.")
    }

    return nil
}


func sendScriptIDs(ids []int) error {
	payload, err := json.Marshal(ids)
	log.Printf("Sending payload: %s", payload)
	if err != nil {
		return fmt.Errorf("error marshalling JSON: %w", err)
	}

	url := "http://172.17.0.1:8100/analyze"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("error creating POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing POST request: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("POST request to %s returned status: %s", url, resp.Status)
	return nil
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
