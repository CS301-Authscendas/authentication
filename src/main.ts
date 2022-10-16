import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { MqService } from "./mq/mq.service";

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const configService = app.get(ConfigService);

    // Consumer queues:
    const mqService = app.get<MqService>(MqService);
    app.connectMicroservice(mqService.getOptions("auth"));

    await app.startAllMicroservices();
    await app.listen(configService.get("PORT") ?? 3001);
}
bootstrap();
