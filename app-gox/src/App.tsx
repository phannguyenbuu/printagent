import { AppRouter } from './router';
import ToastContainer from './components/ui/ToastContainer';
import { ThemeProvider } from './theme/ThemeContext';
import './styles/global.css';

export default function App() {
  return (
    <ThemeProvider>
      <AppRouter />
      <ToastContainer />
    </ThemeProvider>
  );
}
