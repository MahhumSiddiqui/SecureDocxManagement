import { config } from "../../config.js";
import * as secure from "./secure/audit.controller.js";
import * as vulnerable from "./vulnerable/audit.controller.js";
export const auditController = config.secureMode ? secure : vulnerable;
