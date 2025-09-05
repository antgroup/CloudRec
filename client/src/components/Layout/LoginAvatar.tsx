import { UserOutlined } from '@ant-design/icons';
import { Avatar } from 'antd';
import SMILE_AVATAR from '@/assets/images/SMILE.svg';

interface ILoginAvatar {
  userId: number | null;
}

const LoginAvatar = (props: ILoginAvatar) => {
  const { userId } = props;
  return (
    <>
      {userId ? (
        <Avatar size={30} src={SMILE_AVATAR} />
      ) : (
        <Avatar size={30} icon={<UserOutlined />} />
      )}
    </>
  );
};
export default LoginAvatar;
