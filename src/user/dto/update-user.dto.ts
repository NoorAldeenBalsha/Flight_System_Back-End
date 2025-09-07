import { IsOptional, IsString, IsEnum } from 'class-validator';
import { UserGender } from 'utilitis/enums';

export class UpdateUserDto {
  @IsOptional()
  @IsString()
  fullName?: string;

  @IsOptional()
  @IsString()
  password?: string;

  @IsOptional()
  @IsEnum(UserGender)
  gender?: UserGender;

  @IsOptional()
  @IsString()
  phone?: string;
}