import React from 'react';

interface LogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
}

export const Logo: React.FC<LogoProps> = ({ size = 'md', className = '' }) => {
  // Height sizing for responsive, crisp display while strictly maintaining aspect ratio
  const sizeClasses = {
    sm: 'h-8 sm:h-9',
    md: 'h-10 sm:h-11 md:h-12',
    lg: 'h-16 sm:h-20',
    xl: 'h-24 sm:h-28'
  };

  return (
    <img
      src="/logo.png"
      alt="Scam Shield"
      className={`${sizeClasses[size]} w-auto object-contain select-none ${className}`}
      loading="eager"
    />
  );
};
