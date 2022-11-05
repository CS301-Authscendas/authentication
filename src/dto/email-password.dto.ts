import { IsNotEmpty, IsString } from "class-validator";

export class EmailPasswordDTO {
    @IsString()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    password: string;
}
