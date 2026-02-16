export interface UserResponseDTO {
    id: string;
    userName: string | null;
    fullName: string | null;
    role: string;
    updated: boolean | false;
}