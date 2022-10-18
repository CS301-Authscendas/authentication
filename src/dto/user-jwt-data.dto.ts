import { Jwt } from "jsonwebtoken";
import { UserJSONPayload } from "./user-json-payload.dto";

export interface UserJWTData extends Jwt, UserJSONPayload {}
