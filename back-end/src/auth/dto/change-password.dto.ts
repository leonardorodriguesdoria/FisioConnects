/* eslint-disable prettier/prettier */
import { IsString, IsStrongPassword } from 'class-validator';

export class ChangePasswordDto {
  @IsString()
  oldPassword: string;

  @IsStrongPassword(
    {
      minLength: 6,
      minLowercase: 1,
      minUppercase: 1,
      minSymbols: 1,
    },
    {
      message:
        'A senha deve ter no minímo 6 caracteres, incluindo: 1 letra maiúscula, 1 letra minúscula, e 1 carctere especial',
    },
  )
  newPassword: string;
}
