import { App } from "cdktf";
import { ZillaPlusWebStreamingStack } from "./web-streaming-stack";

const app = new App();
new ZillaPlusWebStreamingStack(app, "web-streaming");
app.synth();
