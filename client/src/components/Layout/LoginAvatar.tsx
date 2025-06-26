import { UserOutlined } from '@ant-design/icons';
import { Avatar } from 'antd';
import DEFAULT_AVATAR from '@/assets/images/DEFAULT_AVATAR.svg';

interface ILoginAvatar {
  userId: number | null;
}

const LoginAvatar = (props: ILoginAvatar) => {
  const { userId } = props;
  return (
    <>
      {userId ? (
        <Avatar src={DEFAULT_AVATAR} />
      ) : (
        <Avatar size={32} icon={<UserOutlined />} />
      )}
    </>
  );
};
export default LoginAvatar;
