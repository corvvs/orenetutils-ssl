COLOR_POSITIVE = "\e[32m"
COLOR_NEGATIVE = "\e[31m"
COLOR_RESET = "\e[0m"

# https://datatracker.ietf.org/doc/html/rfc6070
Cases = [
    {
        s: "salt",
        p: "password",
        c: 1,
        dklen: 20,
        answer: "0c60c80f961f0e71f3a9b524af6012062fe037a6",
    },
    {
        s: "salt",
        p: "password",
        c: 2,
        dklen: 20,
        answer: "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
    },
    {
        s: "salt",
        p: "password",
        c: 4096,
        dklen: 20,
        answer: "4b007901b765489abead49d926f721d065a429c1",
    },
    {
        s: "salt",
        p: "password",
        c: 16777216,
        dklen: 20,
        answer: "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984",
    },
    {
        s: "saltSALTsaltSALTsaltSALTsaltSALTsalt",
        p: "passwordPASSWORDpassword",
        c: 4096,
        dklen: 25,
        answer: "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
    },
    {
        s: "sa\0lt",
        p: "pass\0word",
        c: 4096,
        dklen: 16,
        answer: "56fa6aa75548099dcc37d7f03425e0c3",
    },
]

def bin2str(str)
  if str.match(/^[[:print:]]*$/)
    "\"#{str}\""
  else
    str.unpack("H*").first
  end
end


oks = 0
kos = 0

Cases.each_with_index{ |ca, i|

  case_id = i + 1
  puts "[test for \##{case_id}]"

  p = ca[:p]
  s = ca[:s]
  c = ca[:c]
  dklen = ca[:dklen]
  expected = ca[:answer]

  puts "p:\t (#{p.size}) #{bin2str(p)}"
  puts "s:\t (#{s.size}) #{bin2str(s)}"
  puts "c:\t #{c}"
  puts "dklen:\t #{dklen}"

  IO.write("salt", s)
  IO.write("data", p)

  ans = `./ft_ssl pbkdf2 -s salt -c #{c} -l #{dklen} data 2> /dev/null `.chomp
  ok = ans == expected
  puts "[#{ok ? (COLOR_POSITIVE + "ok" + COLOR_RESET) : (COLOR_NEGATIVE + "KO" + COLOR_RESET)}] #{case_id}:\t#{ans}"
  if !ok
    puts "expected answer is:\n        #{expected}"
  end
  oks += 1 if ok
  kos += 1 if !ok
  puts ""

}

all_ok = kos == 0
puts "<summary>"
puts all_ok ? (COLOR_POSITIVE + "ok" + COLOR_RESET) : (COLOR_NEGATIVE + "KO" + COLOR_RESET)
puts "passed #{oks} / #{oks + kos} cases"
if !all_ok
  exit 1
end
