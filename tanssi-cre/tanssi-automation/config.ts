import { z } from "zod";

export const configSchema = z.object({
  schedule: z.string(),
  url: z.string(),
  evms: z.array(
    z.object({
      middleware: z.string(),
      chainSelectorName: z.string(),
      gasLimit: z.string(),
    })
  ),
});

export type Config = z.infer<typeof configSchema>;
