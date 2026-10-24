import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import './styles/base.css';
import './styles/layout.css';
import './styles/components.css';
import './styles/pages.css';

import { render } from 'preact';
import { App } from './app';
import { installRipple } from './ripple';

installRipple();
render(<App />, document.getElementById('app')!);
