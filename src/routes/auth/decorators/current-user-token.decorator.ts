import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CurrentUserToken = createParamDecorator(
  (_data: unknown, context: ExecutionContext): string => {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }

    // Extract the token by removing the 'Bearer ' prefix
    return authHeader.replace('Bearer ', '').trim();
  },
);
