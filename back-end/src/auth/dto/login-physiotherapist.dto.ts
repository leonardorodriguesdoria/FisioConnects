/* eslint-disable prettier/prettier */
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class LoginPhysiotherapistDto {
  @IsEmail({}, { message: 'Por favor insira um endereço de e-mail válido!!!' })
  @IsNotEmpty()
  email: string;

  @IsString()
  @MinLength(6, { message: 'Senha de login deve ter no minímo 6 caracteres' })
  password: string;
}
