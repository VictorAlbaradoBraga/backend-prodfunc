import { NextApiRequest, NextApiResponse } from "next";
import Cors from "cors"; // Importando o pacote CORS
import { authAdmin } from "../utils/firebaseAdmin";
import { UnauthorizedError, sendErrorResponse } from "../utils/errorHandler";

// Inicializando o middleware CORS
const cors = Cors({
  methods: ["GET", "POST", "OPTIONS"],  // Definindo os métodos permitidos
  origin: process.env.CORS_ORIGIN || "http://localhost:5173",  // Definindo a origem do frontend
});

// Função para rodar o middleware CORS
const runCors = (req: NextApiRequest, res: NextApiResponse, next: Function) => {
  cors(req, res, (result: any) => {
    if (result instanceof Error) {
      return next(result);
    }
    next();
  });
};

export type NextApiHandlerWithAuth = (
  req: NextApiRequest & { uid?: string },
  res: NextApiResponse
) => Promise<void> | void;

export async function withAuth(
  handler: NextApiHandlerWithAuth
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    try {
      // Rodar o middleware CORS primeiro
      runCors(req, res, async () => {
        // Verificar se o token está presente no cabeçalho de autorização
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          throw new UnauthorizedError("Token de autenticação não fornecido");
        }

        const token = authHeader.split(" ")[1];
        if (!token) {
          throw new UnauthorizedError("Token de autenticação inválido");
        }

        try {
          // Verificar o token com o Firebase
          const decodedToken = await authAdmin.verifyIdToken(token);
          
          // Adicionar o UID do usuário ao objeto de requisição
          (req as any).uid = decodedToken.uid;
          
          // Chamar o handler original
          return await handler(req as NextApiRequest & { uid: string }, res);
        } catch (error) {
          throw new UnauthorizedError("Token de autenticação inválido ou expirado");
        }
      });
    } catch (error) {
      sendErrorResponse(res, error);
    }
  };
}
