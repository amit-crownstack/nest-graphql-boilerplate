import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { validationOptions } from './common/utils/validation-options';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import * as hbs from 'hbs';
import * as hbsLayouts from 'handlebars-layouts'; // Import the layouts helper

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

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

  // CONFIGURE HANDELBAR FOR HTML RENDER
  app.useStaticAssets(join(__dirname, '..', 'public'));
  app.setBaseViewsDir(join(__dirname, '..', 'views'));
  app.setViewEngine('hbs');
  hbs.registerPartials(join(__dirname, '..', 'views', 'partials'));
  hbsLayouts.register(hbs);

  // APP STARTED ON PORT 8000
  await app.listen(process.env.PORT ?? 8000);
}
bootstrap();
