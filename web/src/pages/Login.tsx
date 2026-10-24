import { useState } from 'preact/hooks';
import { login } from '../api';
import { Blob } from '../components/expressive';
import { Icon } from '../components/Icon';
import { Button, Field } from '../components/ui';

export function Login() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="login">
      <div class="login__inner">
        <div class="login__emblem" aria-hidden="true">
          <Blob shape="cookie12" class="login__blob login__blob--back" />
          <Blob shape="clover" class="login__blob login__blob--front" />
          <span class="login__logo">
            <img src="/logo.png" width={46} height={46} alt="" />
          </span>
        </div>
        <h1 class="login__title">Ezhik Guard</h1>
        <p class="login__text">Защита VPN-нод от торрентов и сканирования, управление SSL-сертификатами</p>
        <form class="card login__card" onSubmit={submit}>
          <div class="stack">
            <Field label="Логин">
              <input class="input" value={username} autoComplete="username" onInput={(e) => setUsername(e.currentTarget.value)} />
            </Field>
            <Field label="Пароль" error={error}>
              <input
                class="input"
                type="password"
                value={password}
                autoComplete="current-password"
                autoFocus
                onInput={(e) => setPassword(e.currentTarget.value)}
              />
            </Field>
            <Button variant="primary" size="lg" block loading={busy} iconRight="arrowRight" type="submit" disabled={!password}>
              Войти
            </Button>
          </div>
        </form>
        <div class="login__hint tiny faint">
          <Icon name="lock" size={13} />
          Пароль показан установщиком. Сброс: <span class="mono">install.sh --reset-password</span>
        </div>
      </div>
    </div>
  );
}
