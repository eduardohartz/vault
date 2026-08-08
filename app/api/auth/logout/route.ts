import { apiJson } from "@/lib/api"
import { destroyCurrentSession } from "@/lib/session"

export async function POST() {
  await destroyCurrentSession()
  return apiJson({ success: true })
}
