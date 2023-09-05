arg=${1}
./ft_ssl "${arg}" 2> /dev/null > mine
echo -n "${arg}" | openssl/apps/openssl md5  2> /dev/null | ruby -e 'puts gets.split[-1]' > ref
diff mine ref
