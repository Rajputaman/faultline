package scoring

import (
	"fmt"
	"strconv"

	"github.com/faultline-go/faultline/internal/report"
)

func evidence(key string, value any, source string) report.Evidence {
	return report.Evidence{
		Key:    key,
		Value:  fmt.Sprint(value),
		Source: source,
	}
}

func evidenceFloat(key string, value float64, source string) report.Evidence {
	return report.Evidence{
		Key:    key,
		Value:  strconv.FormatFloat(round2(value), 'f', 2, 64),
		Source: source,
	}
}
