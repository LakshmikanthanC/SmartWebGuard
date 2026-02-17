import { TailFile } from "tail-file";
import geoip from "geoip-lite";
import Alert from "./models/Alert.js";
import { getRecommendations } from "./services/recommendation.js";
import { getUrlRecommendation } from "./services/recommendation.js";

export function tailEve(wsEmit) {
  const tf = new TailFile("/eve/eve.json", { encoding: "utf8" });

  tf.on("line", async (line) => {
    try {
      const j = JSON.parse(line);
      if (j.event_type !== "alert") return;

      const fileType = j.fileinfo?.file_type || j.fileinfo?.magic;

      const doc = {
        sourceIP: j.src_ip,
        destinationIP: j.dest_ip,
        attackType: j.alert?.signature ?? "unknown",
        severity: Number(j.alert?.severity ?? 0),
        file_type: fileType,
        timestamp: new Date(j.timestamp),
        geo: geoip.lookup(j.src_ip),
        recommendations: getRecommendations(fileType)
      };

      const rec = getUrlRecommendation(j.alert?.signature);
      doc.explanation = rec.explanation;
      doc.recommendations = rec.steps;

      await Alert.create(doc);
      wsEmit(doc);
    } catch {
      /* ignore bad JSON lines */
    }
  });

  tf.start().catch(console.error);
}