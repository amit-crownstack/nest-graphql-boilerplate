import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '../users/entity/user.entity';
import { AuthController } from './auth.controller';
import { AuthService } from './provider/auth.service';
import { ResponseFormatterService } from 'src/common/helper_services/response_formatter.service';
import { UsersService } from '../users/provider/user.service';
import { AccessTokenStrategy } from './strategies/access-token.strategy';
import { RefreshTokenStrategy } from './strategies/refresh-token.strategy';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { UserSession } from './entity/session.entity';
@Module({
  imports: [
    TypeOrmModule.forFeature([UserEntity, UserSession]),
    PassportModule,
    JwtModule.register({}),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    ResponseFormatterService,
    UsersService,
    AccessTokenStrategy,
    RefreshTokenStrategy,
  ],
})
export class AuthModule {}
