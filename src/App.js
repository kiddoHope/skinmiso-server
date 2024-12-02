import logo from './logo.svg';
import './App.css';
import Confirmationtemplate from './confirmationTemplate';

function App() {
  const code = "codeasd"
  return (
    <div className="App">
      <Confirmationtemplate code={code}/>
    </div>
  );
}

export default App;
