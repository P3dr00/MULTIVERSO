// Supabase Edge Function: vertice-users
// Configure: Verify JWT enabled. Uses built-in SUPABASE_URL, SUPABASE_ANON_KEY,
// SUPABASE_SERVICE_ROLE_KEY environment variables inside Supabase only.
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8',
};
const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: cors });
const errText = (error: unknown) => error instanceof Error ? error.message : 'Erro inesperado';

Deno.serve(async (request: Request) => {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (request.method !== 'POST') return json({ error: 'Método não permitido.' }, 405);
  try {
    const url = Deno.env.get('SUPABASE_URL');
    const anon = Deno.env.get('SUPABASE_ANON_KEY');
    const service = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    if (!url || !anon || !service) return json({ error: 'Variáveis do servidor ausentes.' }, 500);
    const bearer = request.headers.get('authorization') || '';
    const token = bearer.startsWith('Bearer ') ? bearer.slice(7) : '';
    if (!token) return json({ error: 'Faça login para continuar.' }, 401);
    const client = createClient(url, anon, { auth: { persistSession: false } });
    const { data: verified, error: authError } = await client.auth.getUser(token);
    if (authError || !verified.user) return json({ error: 'Sessão inválida ou expirada.' }, 401);

    const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });
    const { data: permissions, error: pError } = await admin.from('admins')
      .select('user_id').eq('user_id', verified.user.id).maybeSingle();
    if (pError) throw pError;
    if (!permissions) return json({ error: 'Você não tem permissão de administrador.' }, 403);

    let payload: Record<string, unknown>;
    try { payload = await request.json(); } catch { return json({ error: 'JSON inválido.' }, 400); }
    const action = payload.action;
    if (action === 'list') {
      const users = [];
      for (let page = 1; page <= 30; page++) {
        const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 100 });
        if (error) throw error;
        users.push(...data.users);
        if (data.users.length < 100) break;
      }
      const ids = users.map(u => u.id);
      const admins = new Set<string>();
      const names = new Map<string, string>();
      for (let i = 0; i < ids.length; i += 200) {
        const chunk = ids.slice(i, i + 200);
        const [a, p] = await Promise.all([
          admin.from('admins').select('user_id').in('user_id', chunk),
          admin.from('profiles').select('id,username').in('id', chunk),
        ]);
        if (a.error) throw a.error;
        if (p.error) throw p.error;
        for (const item of a.data || []) admins.add(item.user_id);
        for (const item of p.data || []) names.set(item.id, item.username || '');
      }
      return json({ users: users.map(u => ({
        id: u.id, email: u.email || '',
        username: names.get(u.id) || String(u.user_metadata?.username || u.email?.split('@')[0] || ''),
        is_admin: admins.has(u.id), confirmed: Boolean(u.email_confirmed_at || u.confirmed_at),
        created_at: u.created_at,
      })) });
    }
    if (action === 'create') {
      const username = String(payload.username || '').trim();
      const email = String(payload.email || '').trim().toLowerCase();
      const password = String(payload.password || '');
      const makeAdmin = payload.admin === true;
      if (username.length < 2 || username.length > 60) return json({ error: 'Nome inválido.' }, 400);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'E-mail inválido.' }, 400);
      if (password.length < 8 || password.length > 200) return json({ error: 'A senha deve ter entre 8 e 200 caracteres.' }, 400);
      const { data, error } = await admin.auth.admin.createUser({ email, password,
        email_confirm: true, user_metadata: { username } });
      if (error || !data.user) return json({ error: error?.message || 'Falha ao criar conta.' }, 400);
      if (makeAdmin) {
        const result = await admin.from('admins').insert({ user_id: data.user.id });
        if (result.error) {
          // Avoid leaving a partially configured privileged account.
          await admin.auth.admin.deleteUser(data.user.id);
          throw result.error;
        }
      }
      return json({ user_id: data.user.id, created: true }, 201);
    }
    if (action === 'role' || action === 'delete') {
      const id = String(payload.user_id || '');
      if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: 'Identificador inválido.' }, 400);
      if (id === verified.user.id) return json({ error: 'Não é permitido modificar sua conta atual.' }, 403);
      const { data: target, error: targetError } = await admin.auth.admin.getUserById(id);
      if (targetError || !target.user) return json({ error: 'Usuário não encontrado.' }, 404);
      if (action === 'role') {
        const result = payload.admin === true
          ? await admin.from('admins').upsert({ user_id: id })
          : await admin.from('admins').delete().eq('user_id', id);
        if (result.error) throw result.error;
        return json({ updated: true });
      }
      const { error } = await admin.auth.admin.deleteUser(id);
      if (error) throw error;
      return json({ deleted: true });
    }
    return json({ error: 'Ação não reconhecida.' }, 400);
  } catch (error) {
    console.error('vertice-users:', errText(error));
    return json({ error: errText(error) }, 500);
  }
});
