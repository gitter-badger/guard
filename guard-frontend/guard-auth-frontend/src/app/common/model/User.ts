export class User {

  constructor(
    public givenName: string,
    public familyName: string,
    public email: string,
    public pwd: string,
    public address: string,
    public phoneNumber: number,
    public pin: number,
    public securityQuestion: any
  ) {}
}
