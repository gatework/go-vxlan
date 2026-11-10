package report

import (
	"context"
	"fmt"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

// PublishCollectionDevice persists accepted evidence before its human-readable report.
func (r *Report) PublishCollectionDevice(ctx context.Context, document, result vxlan.Record) error {
	device := record.Map(result["device"])
	name := Basename(device)
	if err := r.PublishJSON(ctx, "evidence/"+name+".json", document); err != nil {
		return err
	}
	encoded, err := EncodeJSON(document["assessment"])
	if err != nil {
		return err
	}
	text := fmt.Sprintf("设备：%s（%s）\n状态：%s\n证据完整性不代表 Fabric 健康；以下为单设备风险评估，Fabric 一致性见 review。\n", device["name"], device["host"], result["status"]) + string(encoded)
	return r.Publish(ctx, "devices/"+name+".txt", []byte(text))
}
