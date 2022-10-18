import { HttpModule } from "@nestjs/axios";
import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { ClientsModule } from "@nestjs/microservices";
import { MqModule } from "../mq/mq.module";
import { MqService } from "../mq/mq.service";
import { UserService } from "./user.service";

@Module({
    imports: [
        HttpModule,
        ConfigModule,
        MqModule,
        ClientsModule.registerAsync([
            {
                name: "USER_RMQ_SERVICE",
                imports: [MqModule],
                inject: [MqService],
                useFactory: (mqService: MqService) => mqService.getClientProvider("user"),
            },
        ]),
    ],
    providers: [UserService],
    exports: [UserService],
})
export class UserModule {}
