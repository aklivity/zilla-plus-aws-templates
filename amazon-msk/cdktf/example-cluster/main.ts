import { App } from "cdktf";
import { ZillaPlusExampleMskCluster } from "./example-cluster-stack";

const app = new App();
new ZillaPlusExampleMskCluster(app, "zilla-plus-example-cluster");
app.synth();
