import { App } from "cdktf";
import { ZillaPlusIotAndControlStack } from "./iot-ingest-and-control-stack";

const app = new App();
new ZillaPlusIotAndControlStack(app, "iot-ingest-and-control");
app.synth();
