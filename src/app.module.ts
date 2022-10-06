import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { AppController } from "./app.controller";
import { NotificationModule } from "./notification/notification.module";
import { NotificationService } from "./notification/notification.service";
import { UserModule } from "./user/user.module";
import { UserService } from "./user/user.service";

@Module({
    imports: [ConfigModule.forRoot({ isGlobal: true }), UserModule, NotificationModule],
    controllers: [AppController],
    providers: [UserService, NotificationService],
})
export class AppModule {}
