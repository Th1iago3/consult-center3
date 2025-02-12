<?php
function processar_cpf($cpf) {
    $credentials = getenv('PNI_CREDENTIALS') ?: 'carlinhos.edu.10@hotmail.com:#Esp210400'; // Use variáveis de ambiente para segurança
    $credentials_base64 = base64_encode($credentials);
    $url_login = 'https://servicos-cloud.saude.gov.br/pni-bff/v1/autenticacao/tokenAcesso';
    $url_pesquisa_base = 'https://servicos-cloud.saude.gov.br/pni-bff/v1/cidadao/cpf/';
    $headers_login = [
        "Host: servicos-cloud.saude.gov.br",
        "Connection: keep-alive",
        "Content-Length: 0",
        "sec-ch-ua: \"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
        "accept: application/json",
        "X-Authorization: Basic $credentials_base64",
        "sec-ch-ua-mobile: ?0",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "sec-ch-ua-platform: Windows",
        "Origin: https://si-pni.saude.gov.br",
        "Sec-Fetch-Site: same-site",
        "Sec-Fetch-Mode: cors",
        "Sec-Fetch-Dest: empty",
        "Referer: https://si-pni.saude.gov.br/",
        "Accept-Encoding: gzip, deflate, br",
        "Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"
    ];
    $max_retries = 3; 
    $retry_delay = 5; 

    for ($i = 0; $i < $max_retries; $i++) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url_login);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers_login);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $response_login = curl_exec($ch);
        if ($response_login === false) {
            curl_close($ch);
            sleep($retry_delay); 
            continue;
        }
        curl_close($ch);
        $login_data = json_decode($response_login, true);
        if (isset($login_data['accessToken'])) {
            $token_acesso = $login_data['accessToken'];
            $url_pesquisa = $url_pesquisa_base . $cpf;
            $headers_pesquisa = [
                'Host: servicos-cloud.saude.gov.br',
                "Authorization: Bearer $token_acesso",
                'Accept: application/json, text/plain, */*',
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
                'Origin: https://si-pni.saude.gov.br',
                'Sec-Fetch-Site: same-site',
                'Sec-Fetch-Mode: cors',
                'Sec-Fetch-Dest: empty',
                'Referer: https://si-pni.saude.gov.br/',
                'Accept-Encoding: gzip, deflate, br',
                'Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7'
            ];

            for ($j = 0; $j < $max_retries; $j++) {
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url_pesquisa);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers_pesquisa);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
                $response_pesquisa = curl_exec($ch);
                if ($response_pesquisa === false) {
                    curl_close($ch);
                    sleep($retry_delay);
                    continue;
                }
                curl_close($ch);
                $dados_pessoais = json_decode($response_pesquisa, true);
                if (isset($dados_pessoais['records'])) {
                    return formatar_informacoes($dados_pessoais['records'][0]);
                } else {
                    return "<div class='alert alert-error'>Erro na pesquisa: " . htmlspecialchars($response_pesquisa) . "</div>";
                }
            }
            return "<div class='alert alert-error'>Falha na requisição de pesquisa após várias tentativas</div>";
        } else {
            return "<div class='alert alert-error'>Erro no login: " . htmlspecialchars($response_login) . "</div>";
        }
    }

    return "<div class='alert alert-error'>Falha na requisição de login após várias tentativas</div>";
}

function formatar_informacoes($dados_pessoais) {
    // Formatar a data de nascimento e calcular a idade
    $dataNascimento = isset($dados_pessoais['dataNascimento']) ? $dados_pessoais['dataNascimento'] : 'SEM INFORMAÇÃO';
    $idade = 'SEM INFORMAÇÃO';
    if ($dataNascimento != 'SEM INFORMAÇÃO') {
        try {
            $dataNascimentoObj = new DateTime($dataNascimento);
            $hoje = new DateTime();
            $idade = $hoje->diff($dataNascimentoObj)->y . " anos";
        } catch (Exception $e) {
            $idade = 'DATA INVÁLIDA';
        }
    }

    // Verificar se 'endereco' é um array antes de acessar
    $endereco = isset($dados_pessoais['endereco']) && is_array($dados_pessoais['endereco']) ? $dados_pessoais['endereco'] : [];

    // Verificar individualmente os campos do endereço
    $logradouro = isset($endereco['logradouro']) ? $endereco['logradouro'] : 'SEM INFORMAÇÃO';
    $cidade = isset($endereco['cidade']) ? $endereco['cidade'] : 'SEM INFORMAÇÃO';
    $bairro = isset($endereco['bairro']) ? $endereco['bairro'] : 'SEM INFORMAÇÃO';
    $cep = isset($endereco['cep']) ? $endereco['cep'] : 'SEM INFORMAÇÃO';

    // Construir a string com os dados formatados
    $output = "<div class='profile-info'>";
    $output .= "<p><strong>NOME:</strong> " . htmlspecialchars($dados_pessoais['nome'] ?? 'SEM INFORMAÇÃO') . "</p>";
    $output .= "<p><strong>CPF:</strong> " . htmlspecialchars($dados_pessoais['cpf'] ?? 'SEM INFORMAÇÃO') . "</p>";
    $output .= "<p><strong>NOME DA MÃE:</strong> " . htmlspecialchars($dados_pessoais['nomeMae'] ?? 'SEM INFORMAÇÃO') . "</p>";
    $output .= "<p><strong>NOME DO PAI:</strong> " . htmlspecialchars($dados_pessoais['nomePai'] ?? 'SEM INFORMAÇÃO') . "</p>";
    $output .= "<p><strong>CNS:</strong> " . htmlspecialchars($dados_pessoais['cns'] ?? 'SEM INFORMAÇÃO') . "</p>";
    $output .= "<p><strong>Nascimento:</strong> $dataNascimento ($idade)</p>";
    $output .= "<p><strong>EMAIL:</strong> " . htmlspecialchars($dados_pessoais['email'] ?? 'SEM INFORMAÇÃO') . "</p>";
    $output .= "<p><strong>Sexo:</strong> " . htmlspecialchars($dados_pessoais['sexo'] ?? 'SEM INFORMAÇÃO') . " ";
    $output .= "<strong>Cor:</strong> " . htmlspecialchars($dados_pessoais['racaCor'] ?? 'SEM INFORMAÇÃO') . " ";
    $output .= "<strong>Grau de Qualidade:</strong> " . htmlspecialchars($dados_pessoais['grauQualidade'] ?? 'SEM INFORMAÇÃO') . "</p>";

    // Endereço formatado corretamente
    $output .= "<p><strong>Endereço:</strong><br>";
    $output .= "Logradouro: " . htmlspecialchars($logradouro) . "<br>";
    $output .= "Cidade: " . htmlspecialchars($cidade) . "<br>";
    $output .= "Bairro: " . htmlspecialchars($bairro) . "<br>";
    $output .= "CEP: " . htmlspecialchars($cep) . "<br>";
    $output .= "Número: ( manutenção )</p>";

    // Dados usados
    $output .= "<p><strong>DADOS USADOS:</strong><br>";
    $output .= "CPF: " . htmlspecialchars($dados_pessoais['cpf'] ?? 'SEM INFORMAÇÃO') . "<br>";
    
    $output .= "</div>";

    return $output;
}

header('Content-Type: text/html; charset=utf-8');

if (isset($_GET['cpf'])) {
    $cpf = $_GET['cpf'];
    echo processar_cpf($cpf);
} else {
    echo "<div class='alert alert-error'>Por favor, forneça o CPF na URL como ?cpf=seu_cpf</div>";
}
?>
