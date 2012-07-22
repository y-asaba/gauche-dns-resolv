# gauche-dns-resolv
このモジュールは Gauche 用の DNS resolver ライブラリです。

## インストール
gauche-install および gauche-config を使ってインストールします。
${GAUCHE}/share/gauche/site/lib にインストールする場合は、次のコマンド
でインストールします。

> gauche-install -T `gauche-config --sitelibdir` -m 644 dns/resolv.scm

他のディレクトリにインストールしたい場合は、-T の引数にディレクトリを
指定してください。

## 使い方
このモジュールを使うには、まずモジュールを使用することを宣言します。

    (use dns.resolv)

次に <resolver> オブジェクトを作成します。

    (define resolver (make <resolver>))

/etc/resolv.conf の内容からネームサーバのリストを構築します。なお、
/etc/resolv.conf の内容から nameserver の値のみを解析します。それ以外
(search 等)については今のところ無視します。

    (resolv:name->address resolver "www.foo.bar.jp")
    (resolv:get-resource-records resolver "www.foo.bar.jp" 'A)
    (resolv:get-resource-records resolver "www.foo.bar.jp" RR:A)
    
    (resolv:address->name resolver "11.22.33.44")

## ライセンス
COPYING を参照してください。

## ドキュメント
doc/ 以下を参照してください。

## 問い合わせ先
コメントや要望などがありましたら、以下のアドレスへメールしてください。
ysyk.asaba _at_ gmail _dot_ com
