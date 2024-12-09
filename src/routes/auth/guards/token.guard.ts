import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';

@Injectable()
export class TokenGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();

    // Extract the authorization header
    const authHeader = request.headers['authorization'];

    // Check if authorization header exists
    if (!authHeader) {
      throw new UnauthorizedException('No authorization header');
    }

    // Check if it's a bearer token
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new UnauthorizedException('Invalid authorization header format');
    }

    // Extract the refresh token
    const refreshToken = parts[1];

    // Validate refresh token
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is missing');
    }

    // Attach the refresh token to the request for strategy to use
    request['refreshToken'] = refreshToken;

    return true;
  }
}
