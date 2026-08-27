export function root(req: Request, res: Response): void {}
export function listFeatures(req: Request, res: Response): void {}
export function getFeature(req: Request, res: Response): void {}
export function toggleOff(req: Request, res: Response): void {}
export function archive(req: Request, res: Response): void {}
export function validate(req: Request, res: Response): void {}

interface Request {
  params: Record<string, string>;
  query: Record<string, string>;
}

interface Response {
  send(body: string): void;
}
