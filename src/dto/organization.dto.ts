import { IsNumber, IsString } from "class-validator";

export class Organization {
    @IsString()
    id: string;

    @IsString()
    name: string;

    @IsString()
    jwkToken: string;

    @IsString({ each: true })
    authMethod: string[];

    @IsNumber()
    updatedAt: number;
}
