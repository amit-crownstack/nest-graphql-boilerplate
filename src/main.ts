import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { validationOptions } from './common/utils/validation-options';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // ADDED GLOBAL API PREFIX
  app.setGlobalPrefix('api');

  // SWAGGER CONFIGURATION
  const config = new DocumentBuilder()
    .setTitle('SERVER APP')
    .setDescription('SERVER APP API BASE URL : http://localhost:8000')
    .setVersion('1.0')
    .addServer('http://localhost:8000')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  // GLOBAL VALIDATION PIPE
  app.useGlobalPipes(new ValidationPipe(validationOptions));

  // APP STARTED ON PORT 8000
  await app.listen(process.env.PORT ?? 8000);
}
bootstrap();
