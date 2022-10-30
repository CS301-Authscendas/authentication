import { HttpModule } from "@nestjs/axios";
import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { OrganizationController } from "./organization.controller";
import { OrganizationService } from "./organization.service";

@Module({
    imports: [ConfigModule, HttpModule, HttpModule.register({})],
    controllers: [OrganizationController],
    providers: [OrganizationService],
})
export class OrganizationModule {}
