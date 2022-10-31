import "reflect-metadata";

import { Logger, ValidationPipe } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { MqService } from "./mq/mq.service";

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    app.useGlobalPipes(new ValidationPipe({ transform: true }));
    const configService = app.get(ConfigService);

    // Consumer queues:
    const mqService = app.get<MqService>(MqService);
    app.connectMicroservice(mqService.getOptions("auth"));

    await app.startAllMicroservices();
    app.enableCors();

    const port = configService.get("PORT");
    Logger.log("Starting service on PORT " + port);
    await app.listen(port ?? 3001);
}
bootstrap();
