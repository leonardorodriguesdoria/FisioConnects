/* eslint-disable prettier/prettier */
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from 'src/auth/auth.service';
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly physiotherapistService: AuthService) {}

  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;

    if (!authHeader) {
      throw new UnauthorizedException('Requisição não autorizada');
    }

    const [bearer, token] = authHeader.split(' ');

    if (bearer !== 'Bearer' || !token) {
      throw new UnauthorizedException('Autorização inválida');
    }

    try {
      const data = this.physiotherapistService.checkToken(token);
      request.tokenPayload = data;
      return true;
    } catch (error) {
      console.error('Auth Guard Error: ', error.message);
      throw new UnauthorizedException('autenticação inválida ou expirada');
    }
  }
}
