import { App } from "cdktf";
import { ZillaPlusSecurePublicAccessStack } from "./secure-public-acces-stack";

const app = new App();
new ZillaPlusSecurePublicAccessStack(app, "secure-public-access");
app.synth();
