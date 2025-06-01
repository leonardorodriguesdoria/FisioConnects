import {
  IsString,
  IsEmail,
  IsStrongPassword,
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsArray,
  ArrayNotEmpty,
  IsOptional,
} from 'class-validator';

export class CreatePhysiotherapistDto {
  @IsNotEmpty({ message: 'O campo de nome é obrigatório' })
  @IsString({ message: 'Por favor, insira um nome válido' })
  @MinLength(3, { message: 'O nome deve ter pelo menos 3 caracteres' })
  @MaxLength(50, { message: 'O nome deve ter no máximo 50 caracteres' })
  name: string;

  @IsNotEmpty({ message: 'O campo de e-mail é obrigatório' })
  @IsEmail({}, { message: 'Por favor, insira um endereço de email válido' })
  @MaxLength(100, { message: 'O e-mail deve ter no máximo 100 caracteres' })
  email: string;

  @IsString({ message: 'O campo de telefone é obrigatório' })
  @IsNotEmpty()
  phone: string;

  @IsString()
  @IsNotEmpty()
  description: string;

  @IsOptional()
  profilePicture?: string;

  @IsNotEmpty({ message: 'O campo de senha é obrigatório' })
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
  password: string;

  @IsNotEmpty({ message: 'É necessário informar o seu CREFITO' })
  crefito: string;

  @IsArray()
  @ArrayNotEmpty()
  specialties: string[];
}
