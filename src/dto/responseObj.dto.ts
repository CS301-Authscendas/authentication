import { HttpStatus } from "@nestjs/common";

export interface ResponseObjDTO {
    statusCode: HttpStatus;
    message: string;
    data?: Record<string, unknown>;
}
