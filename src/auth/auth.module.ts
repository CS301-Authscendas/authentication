import { HttpModule } from "@nestjs/axios";
import { CacheModule, Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { PassportModule } from "@nestjs/passport";
import { KmsModule } from "../kms/kms.module";
import { NotificationModule } from "../notification/notification.module";
import { OrganizationModule } from "../organization/organization.module";
import { UserModule } from "../user/user.module";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { LoginStrategy } from "./strategy/login.strategy";

@Module({
    imports: [
        ConfigModule,
        HttpModule,
        UserModule,
        NotificationModule,
        OrganizationModule,
        PassportModule,
        KmsModule,
        CacheModule.register({ isGlobal: true, ttl: 15 }),
    ],
    controllers: [AuthController],
    providers: [AuthService, LoginStrategy],
})
export class AuthModule {}
