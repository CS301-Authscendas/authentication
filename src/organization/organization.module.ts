import { HttpModule } from "@nestjs/axios";
import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { OrganizationService } from "./organization.service";

@Module({
    imports: [ConfigModule, HttpModule],
    providers: [OrganizationService],
})
export class OrganizationModule {}
