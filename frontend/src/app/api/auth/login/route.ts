import { NextResponse } from "next/server";

export const GET = async () => {
  return NextResponse.redirect("http://localhost:8080/auth/login");
};
