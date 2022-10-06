import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { RmqContext, RmqOptions, Transport } from "@nestjs/microservices";

@Injectable()
export class NotificationService {
    constructor(private readonly configService: ConfigService) {}

    getOptions(noAck = false): RmqOptions {
        const user = this.configService.get<string>("RABBITMQ_USER");
        const password = this.configService.get<string>("RABBITMQ_PASSWORD");
        const host = this.configService.get<string>("RABBITMQ_HOST");
        const port = this.configService.get<string>("RABBITMQ_PORT");
        const queueName = this.configService.get<string>("RABBITMQ_QUEUE_NAME");

        return {
            transport: Transport.RMQ,
            options: {
                urls: [`amqp://${user}:${password}@${host}:${port}`],
                queue: queueName,
                noAck,
                persistent: true,
            },
        };
    }

    ack(context: RmqContext) {
        const channel = context.getChannelRef();
        const originalMessage = context.getMessage();
        channel.ack(originalMessage);
    }
}
