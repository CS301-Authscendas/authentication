import { Module } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { UserModule } from "../user/user.module";
import { ConfigModule } from "@nestjs/config";
import { NotificationModule } from "../notification/notification.module";
import { AuthController } from "./auth.controller";

@Module({
    imports: [ConfigModule, UserModule, NotificationModule],
    controllers: [AuthController],
    providers: [AuthService],
})
export class AuthModule {}
