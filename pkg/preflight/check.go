package preflight

import (
	"goipsec/pkg/glog"
	"os"
)

func Checklist() {
	glog.Logger.Print("INFO: starting checklist")

	if len(os.Getenv("GOIPSEC_PASSWORD")) != 32 {
		glog.Logger.Fatal("ERROR: env variable GOIPSEC_PASSWORD not found")
	} else {
		glog.Logger.Print("INFO: env variable GOIPSEC_PASSWORD found")
	}
}
