import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { AppController } from "./app.controller";
import { MqModule } from "./mq/mq.module";
import { NotificationModule } from "./notification/notification.module";
import { UserModule } from "./user/user.module";
import { AuthModule } from "./auth/auth.module";

@Module({
    imports: [ConfigModule.forRoot({ isGlobal: true }), UserModule, NotificationModule, MqModule, AuthModule],
    controllers: [AppController],
    providers: [],
})
export class AppModule {}
